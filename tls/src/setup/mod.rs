// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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

/// Result of building a reloadable server config.
///
/// Contains the immutable [`ServerConfig`], the cert swap handle,
/// and an optional client verifier swap handle (when mTLS is
/// configured).
///
/// [`ServerConfig`]: rustls::ServerConfig
#[cfg(feature = "hot-reload")]
pub struct ReloadableServerConfig {
    /// The built server config.
    pub config: Arc<ServerConfig>,

    /// Handle to swap the server certificate atomically.
    pub cert_handle: Arc<arc_swap::ArcSwap<rustls::sign::CertifiedKey>>,

    /// Handle to swap the client verifier atomically (mTLS only).
    pub verifier_handle: Option<Arc<arc_swap::ArcSwap<crate::reload::VerifierState>>>,
}

/// Build a `rustls::ServerConfig` that uses a
/// [`ReloadableCertResolver`] for hot-reload support.
///
/// Returns a [`ReloadableServerConfig`] containing the server
/// config and swap handles for both the certificate and (when
/// mTLS is configured) the client verifier. The watcher task
/// uses these handles to atomically update TLS state on
/// filesystem changes.
///
/// # Errors
///
/// Returns [`TlsError`] if the initial certificate cannot be
/// loaded or the mTLS CA is invalid.
///
/// [`TlsError`]: crate::TlsError
/// [`ReloadableCertResolver`]: crate::reload::ReloadableCertResolver
/// [`ReloadableServerConfig`]: ReloadableServerConfig
#[cfg(feature = "hot-reload")]
pub fn build_reloadable_server_config(tls: &ListenerTls) -> Result<ReloadableServerConfig, TlsError> {
    let builder = build_config_builder(tls)?;

    let (builder, verifier_handle) = if tls.client_cert_mode == ClientCertMode::None {
        (builder.with_no_client_auth(), None)
    } else {
        let ca_cfg = tls.client_ca.as_ref().ok_or(TlsError::MissingClientCa {
            mode: tls.client_cert_mode,
        })?;
        let verifier =
            crate::reload::ReloadableClientVerifier::new(&ca_cfg.ca_path, tls.client_cert_mode, &ca_cfg.crl_paths)?;
        let handle = verifier.arc();
        (builder.with_client_cert_verifier(Arc::new(verifier)), Some(handle))
    };

    let primary = tls.certificates.first().ok_or(TlsError::NoCertificates)?;
    let resolver = crate::reload::ReloadableCertResolver::new(primary)?;
    let cert_handle = resolver.arc();

    let mut config = builder.with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = alpn_protocols();

    Ok(ReloadableServerConfig {
        config: Arc::new(config),
        cert_handle,
        verifier_handle,
    })
}

// -----------------------------------------------------------------------------
// Shared Builder Setup
// -----------------------------------------------------------------------------

/// Build the protocol-version and cipher-suite portion of a
/// `ServerConfig`, returning a builder before client auth is
/// configured.
///
/// Used by [`build_reloadable_server_config`] which installs its
/// own reloadable verifier.
///
/// [`build_reloadable_server_config`]: crate::setup::build_reloadable_server_config
#[cfg(feature = "hot-reload")]
fn build_config_builder(
    tls: &ListenerTls,
) -> Result<rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>, TlsError> {
    let versions = match tls.min_version {
        Some(TlsVersion::Tls13) => vec![&version::TLS13],
        Some(TlsVersion::Tls12) | None => {
            vec![&version::TLS12, &version::TLS13]
        },
    };
    let provider = maybe_filter_provider(default_crypto_provider(), tls.cipher_suites.as_deref())?;
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| TlsError::ServerConfigError {
            detail: format!("failed to set TLS protocol versions: {e}"),
        })
}

/// Build the common `ServerConfig` builder: selects TLS versions,
/// installs the crypto provider, and configures client auth.
fn build_server_config_base(
    tls: &ListenerTls,
) -> Result<rustls::ConfigBuilder<ServerConfig, WantsServerCert>, TlsError> {
    let versions = match tls.min_version {
        Some(TlsVersion::Tls13) => vec![&version::TLS13],
        Some(TlsVersion::Tls12) | None => vec![&version::TLS12, &version::TLS13],
    };
    let provider = maybe_filter_provider(default_crypto_provider(), tls.cipher_suites.as_deref())?;
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| TlsError::ServerConfigError {
            detail: format!("failed to set TLS protocol versions: {e}"),
        })?;

    if tls.client_cert_mode == ClientCertMode::None {
        Ok(builder.with_no_client_auth())
    } else {
        let ca_cfg = tls.client_ca.as_ref().ok_or(TlsError::MissingClientCa {
            mode: tls.client_cert_mode,
        })?;
        let verifier = client_auth::build_client_verifier(&ca_cfg.ca_path, tls.client_cert_mode, &ca_cfg.crl_paths)?;
        Ok(builder.with_client_cert_verifier(verifier))
    }
}

// -----------------------------------------------------------------------------
// Cipher Suite Filtering
// -----------------------------------------------------------------------------

/// Return a provider with only the requested cipher suites, or the
/// original provider when no filter is specified.
///
/// # Errors
///
/// Returns [`TlsError::EmptyCipherSuites`] when all requested
/// suites are filtered out (none match the provider).
///
/// [`TlsError::EmptyCipherSuites`]: crate::TlsError::EmptyCipherSuites
fn maybe_filter_provider(
    provider: Arc<rustls::crypto::CryptoProvider>,
    cipher_suites: Option<&[CipherSuiteId]>,
) -> Result<Arc<rustls::crypto::CryptoProvider>, TlsError> {
    let Some(ids) = cipher_suites else {
        return Ok(provider);
    };

    warn_cipher_suite_ordering(ids);

    let filtered: Vec<_> = ids
        .iter()
        .filter_map(|id| {
            let target = id.to_rustls().suite();
            provider.cipher_suites.iter().find(|s| s.suite() == target).copied()
        })
        .collect();

    if filtered.is_empty() {
        return Err(TlsError::EmptyCipherSuites);
    }
    log_cipher_filter_result(ids.len(), filtered.len());

    Ok(Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: filtered,
        ..(*provider).clone()
    }))
}

// -----------------------------------------------------------------------------
// Cipher Suite Ordering
// -----------------------------------------------------------------------------

/// Log the result of cipher suite filtering.
fn log_cipher_filter_result(requested: usize, matched: usize) {
    if matched < requested {
        tracing::warn!(
            requested,
            matched,
            "some requested cipher suites were not found in the provider"
        );
    } else {
        tracing::info!(requested, matched, "cipher suite filter applied");
    }
}

/// Emit a warning when the configured cipher suite order places a
/// weaker cipher before a stronger one.
fn warn_cipher_suite_ordering(suites: &[CipherSuiteId]) {
    if let Some((weaker, stronger)) = find_weak_before_strong(suites) {
        tracing::warn!(
            ?weaker,
            ?stronger,
            "cipher suite ordering places a weaker cipher before a stronger one; \
             consider reordering strongest suites first"
        );
    }
}

/// Strength tier for a cipher suite's symmetric algorithm.
///
/// Higher values indicate stronger ciphers. Used to detect when
/// a weaker cipher is ordered before a stronger one in the
/// operator's configuration.
///
/// - Tier 2: AES-256-GCM (256-bit key, highest security margin)
/// - Tier 1: ChaCha20-Poly1305 (256-bit key, strong alternative)
/// - Tier 0: AES-128-GCM (128-bit key, adequate but lower margin)
fn cipher_strength_tier(suite: &CipherSuiteId) -> u8 {
    match suite {
        CipherSuiteId::Tls13Aes256GcmSha384
        | CipherSuiteId::Tls12EcdheEcdsaWithAes256GcmSha384
        | CipherSuiteId::Tls12EcdheRsaWithAes256GcmSha384 => 2,

        CipherSuiteId::Tls13Chacha20Poly1305Sha256
        | CipherSuiteId::Tls12EcdheEcdsaWithChacha20Poly1305Sha256
        | CipherSuiteId::Tls12EcdheRsaWithChacha20Poly1305Sha256 => 1,

        CipherSuiteId::Tls13Aes128GcmSha256
        | CipherSuiteId::Tls12EcdheEcdsaWithAes128GcmSha256
        | CipherSuiteId::Tls12EcdheRsaWithAes128GcmSha256 => 0,
    }
}

/// Find the first pair where a weaker cipher suite precedes a
/// stronger one in the configured order.
///
/// Returns `None` when the ordering is non-increasing by strength
/// (i.e. strongest-first or all equal).
fn find_weak_before_strong(suites: &[CipherSuiteId]) -> Option<(&CipherSuiteId, &CipherSuiteId)> {
    suites.windows(2).find_map(|w| match (w.first(), w.get(1)) {
        (Some(a), Some(b)) if cipher_strength_tier(a) < cipher_strength_tier(b) => Some((a, b)),
        _ => None,
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
    use crate::{
        CaConfig, CertKeyPair, ClientCertMode, TlsVersion,
        test_utils::{ensure_crypto_provider, gen_test_certs},
    };

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
        ensure_crypto_provider();
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
                crl_paths: Vec::new(),
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
                crl_paths: Vec::new(),
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

        let result = maybe_filter_provider(Arc::clone(&provider), None).expect("None filter should succeed");
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

        let result = maybe_filter_provider(provider, Some(&ids)).expect("single-suite filter should succeed");
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
    fn maybe_filter_provider_preserves_configured_order() {
        let provider = default_crypto_provider();
        let ids = [
            CipherSuiteId::Tls13Chacha20Poly1305Sha256,
            CipherSuiteId::Tls13Aes128GcmSha256,
        ];

        let result = maybe_filter_provider(provider, Some(&ids)).expect("two-suite filter should succeed");
        assert_eq!(
            result.cipher_suites.len(),
            2,
            "filtering to two suites should yield exactly two"
        );
        assert_eq!(
            result.cipher_suites[0].suite(),
            CipherSuiteId::Tls13Chacha20Poly1305Sha256.to_rustls().suite(),
            "first suite should match the first configured cipher"
        );
        assert_eq!(
            result.cipher_suites[1].suite(),
            CipherSuiteId::Tls13Aes128GcmSha256.to_rustls().suite(),
            "second suite should match the second configured cipher"
        );
    }

    #[test]
    fn maybe_filter_provider_reverses_provider_order_when_configured() {
        let provider = default_crypto_provider();
        let ids = [
            CipherSuiteId::Tls13Aes128GcmSha256,
            CipherSuiteId::Tls13Aes256GcmSha384,
            CipherSuiteId::Tls13Chacha20Poly1305Sha256,
        ];
        let reversed = [
            CipherSuiteId::Tls13Chacha20Poly1305Sha256,
            CipherSuiteId::Tls13Aes256GcmSha384,
            CipherSuiteId::Tls13Aes128GcmSha256,
        ];

        let forward = maybe_filter_provider(Arc::clone(&provider), Some(&ids)).expect("forward filter should succeed");
        let backward = maybe_filter_provider(provider, Some(&reversed)).expect("reversed filter should succeed");

        assert_eq!(forward.cipher_suites.len(), 3, "forward should have three suites");
        assert_eq!(backward.cipher_suites.len(), 3, "reversed should have three suites");

        for i in 0..3 {
            assert_eq!(
                forward.cipher_suites[i].suite(),
                backward.cipher_suites[2 - i].suite(),
                "forward[{i}] should equal reversed[{}]",
                2 - i,
            );
        }
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

    #[test]
    #[cfg(feature = "hot-reload")]
    fn build_reloadable_server_config_single_cert() {
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

        let result = build_reloadable_server_config(&tls).expect("reloadable build should succeed");
        assert_eq!(
            result.config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN should include h2 and http/1.1"
        );
        assert!(result.verifier_handle.is_none(), "no mTLS means no verifier handle");
    }

    #[test]
    fn cipher_strength_tier_aes256_is_highest() {
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls13Aes256GcmSha384),
            2,
            "TLS 1.3 AES-256"
        );
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls12EcdheEcdsaWithAes256GcmSha384),
            2,
            "TLS 1.2 ECDSA AES-256"
        );
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls12EcdheRsaWithAes256GcmSha384),
            2,
            "TLS 1.2 RSA AES-256"
        );
    }

    #[test]
    fn cipher_strength_tier_chacha20_is_middle() {
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls13Chacha20Poly1305Sha256),
            1,
            "TLS 1.3 ChaCha20"
        );
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls12EcdheEcdsaWithChacha20Poly1305Sha256),
            1,
            "TLS 1.2 ECDSA ChaCha20"
        );
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls12EcdheRsaWithChacha20Poly1305Sha256),
            1,
            "TLS 1.2 RSA ChaCha20"
        );
    }

    #[test]
    fn cipher_strength_tier_aes128_is_lowest() {
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls13Aes128GcmSha256),
            0,
            "TLS 1.3 AES-128"
        );
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls12EcdheEcdsaWithAes128GcmSha256),
            0,
            "TLS 1.2 ECDSA AES-128"
        );
        assert_eq!(
            cipher_strength_tier(&CipherSuiteId::Tls12EcdheRsaWithAes128GcmSha256),
            0,
            "TLS 1.2 RSA AES-128"
        );
    }

    #[test]
    fn cipher_ordering_strong_first_no_violation() {
        let suites = [
            CipherSuiteId::Tls13Aes256GcmSha384,
            CipherSuiteId::Tls13Chacha20Poly1305Sha256,
            CipherSuiteId::Tls13Aes128GcmSha256,
        ];
        assert!(
            find_weak_before_strong(&suites).is_none(),
            "strongest-first ordering should have no violation"
        );
    }

    #[test]
    fn cipher_ordering_weak_first_detected() {
        let suites = [CipherSuiteId::Tls13Aes128GcmSha256, CipherSuiteId::Tls13Aes256GcmSha384];
        let result = find_weak_before_strong(&suites);
        assert!(result.is_some(), "weak-before-strong should be detected");
        let (weaker, stronger) = result.unwrap();
        assert_eq!(*weaker, CipherSuiteId::Tls13Aes128GcmSha256, "weaker suite identity");
        assert_eq!(
            *stronger,
            CipherSuiteId::Tls13Aes256GcmSha384,
            "stronger suite identity"
        );
    }

    #[test]
    fn cipher_ordering_equal_tiers_no_violation() {
        let suites = [
            CipherSuiteId::Tls12EcdheEcdsaWithAes256GcmSha384,
            CipherSuiteId::Tls12EcdheRsaWithAes256GcmSha384,
        ];
        assert!(
            find_weak_before_strong(&suites).is_none(),
            "same-tier suites should not trigger a violation"
        );
    }

    #[test]
    fn cipher_ordering_single_suite_no_violation() {
        let suites = [CipherSuiteId::Tls13Aes128GcmSha256];
        assert!(
            find_weak_before_strong(&suites).is_none(),
            "single suite should have no violation"
        );
    }

    #[test]
    fn cipher_ordering_non_adjacent_violation() {
        let suites = [
            CipherSuiteId::Tls13Aes256GcmSha384,
            CipherSuiteId::Tls13Aes128GcmSha256,
            CipherSuiteId::Tls13Chacha20Poly1305Sha256,
        ];
        let result = find_weak_before_strong(&suites);
        assert!(result.is_some(), "AES-128 before ChaCha20 should be detected");
        let (weaker, stronger) = result.unwrap();
        assert_eq!(*weaker, CipherSuiteId::Tls13Aes128GcmSha256, "weaker suite identity");
        assert_eq!(
            *stronger,
            CipherSuiteId::Tls13Chacha20Poly1305Sha256,
            "stronger suite identity"
        );
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
