// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Shared TLS settings builder for HTTP and TCP listeners.
//!
//! This module provides [`build_tls_settings`], the unified entry point for
//! constructing Pingora [`TlsSettings`] from a Praxis [`ListenerTls`] config.
//! It is used by both HTTP and TCP protocol adapters to set up listener TLS,
//! handling the distinction between hot-reload and static certificate modes.
//!
//! # Hot-reload vs static certificates
//!
//! When the `config-reload` feature is compiled in AND the listener has
//! `hot_reload: true`, this module builds a reloadable TLS configuration via
//! [`praxis_tls::setup::build_reloadable_server_config`] and spawns a
//! [`CertWatcher`] background task to monitor certificate files for changes.
//! The watcher runs for the process lifetime and swaps certificates
//! atomically when they change on disk, without dropping connections.
//!
//! Otherwise (no `config-reload` feature, or `hot_reload: false`), a static
//! `rustls::ServerConfig` is built via [`praxis_tls::setup::build_server_config`]
//! and certificate changes require a full config reload.
//!
//! # Certificate watcher lifecycle
//!
//! The returned shutdown sender allows the caller to stop the cert watcher
//! early by sending `true`. Dropping the sender does NOT stop the watcher;
//! it continues monitoring until explicitly stopped or the process exits.
//! Callers typically keep the sender alive for the server lifetime.
//!
//! [`build_tls_settings`]: crate::tls_setup::build_tls_settings
//! [`TlsSettings`]: pingora_core::listeners::tls::TlsSettings
//! [`ListenerTls`]: praxis_tls::ListenerTls
//! [`CertWatcher`]: praxis_tls::watcher::CertWatcher

use pingora_core::listeners::tls::TlsSettings;
use praxis_core::ProxyError;
use praxis_tls::ListenerTls;
use tokio::sync::watch;

// -----------------------------------------------------------------------------
// TLS Settings Builder
// -----------------------------------------------------------------------------

/// Build [`TlsSettings`] for a listener.
///
/// When `hot_reload` is enabled (and the `config-reload` feature is
/// compiled in), uses a [`ReloadableCertResolver`] and spawns a
/// [`CertWatcher`] background task. Otherwise, or in a build without
/// `config-reload`, builds a static `ServerConfig` via
/// [`build_server_config`].
///
/// `context_label` appears in debug tracing to distinguish HTTP
/// from TCP callers (e.g. `"HTTP"`, `"TCP"`).
///
/// Returns the settings and an optional shutdown sender for the
/// cert watcher. The watcher runs for the process lifetime; the caller
/// keeps the sender to stop it early via `send(true)` (dropping it does
/// not stop the watcher).
///
/// [`TlsSettings`]: pingora_core::listeners::tls::TlsSettings
/// [`build_server_config`]: praxis_tls::setup::build_server_config
/// [`ReloadableCertResolver`]: praxis_tls::reload::ReloadableCertResolver
/// [`CertWatcher`]: praxis_tls::watcher::CertWatcher
pub(crate) fn build_tls_settings(
    tls: &ListenerTls,
    address: &str,
    context_label: &str,
    advertise_http_alpn: bool,
) -> Result<(TlsSettings, Option<watch::Sender<bool>>), ProxyError> {
    #[cfg(feature = "config-reload")]
    if tls.is_hot_reload() {
        return build_reloadable_tls_settings(tls, address, context_label, advertise_http_alpn);
    }

    // Built without the `config-reload` feature: honor the static cert but warn
    // that a `hot_reload: true` listener will not actually watch for changes.
    #[cfg(not(feature = "config-reload"))]
    if tls.is_hot_reload() {
        tracing::warn!(
            address,
            context_label,
            "listener requests TLS hot_reload but this build lacks the `config-reload` feature; \
             serving a static certificate"
        );
    }

    tracing::debug!(address, context_label, "building TLS ServerConfig");
    let server_config = praxis_tls::setup::build_server_config(tls, advertise_http_alpn)
        .map_err(|e| ProxyError::Config(format!("TLS for {address}: {e}")))?;
    let settings = TlsSettings::with_server_config(server_config)
        .map_err(|e| ProxyError::Config(format!("TLS for {address}: {e}")))?;
    Ok((settings, None))
}

/// Build reloadable [`TlsSettings`] and spawn a [`CertWatcher`] to swap
/// certificates atomically as they change on disk.
///
/// [`TlsSettings`]: pingora_core::listeners::tls::TlsSettings
/// [`CertWatcher`]: praxis_tls::watcher::CertWatcher
#[cfg(feature = "config-reload")]
fn build_reloadable_tls_settings(
    tls: &ListenerTls,
    address: &str,
    context_label: &str,
    advertise_http_alpn: bool,
) -> Result<(TlsSettings, Option<watch::Sender<bool>>), ProxyError> {
    tracing::debug!(address, context_label, "building TLS ServerConfig with hot-reload");
    let result = praxis_tls::setup::build_reloadable_server_config(tls, advertise_http_alpn)
        .map_err(|e| ProxyError::Config(format!("TLS hot-reload for {address}: {e}")))?;

    let pair = tls
        .certificates
        .first()
        .cloned()
        .ok_or_else(|| ProxyError::Config(format!("TLS hot-reload for {address}: no certificate configured")))?;

    let verifier_reload = result.verifier_handle.and_then(|handle| {
        tls.client_ca
            .as_ref()
            .map(|ca_cfg| praxis_tls::watcher::ClientVerifierReload {
                ca_path: ca_cfg.ca_path.clone(),
                crl_paths: ca_cfg.crl_paths.clone(),
                mode: tls.client_cert_mode,
                trusted_spiffe_ids: tls.trusted_spiffe_ids.clone(),
                swap_handle: handle,
            })
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    praxis_tls::watcher::CertWatcher::spawn(result.cert_handle, pair, verifier_reload, shutdown_rx);

    let settings = TlsSettings::with_server_config(result.config)
        .map_err(|e| ProxyError::Config(format!("TLS for {address}: {e}")))?;
    Ok((settings, Some(shutdown_tx)))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::significant_drop_tightening,
    clippy::semicolon_if_nothing_returned,
    clippy::let_underscore_must_use,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use praxis_tls::{CaConfig, CertKeyPair, ClientCertMode};

    use super::*;

    /// Generate test certificates for TLS testing.
    ///
    /// Returns a temporary directory and paths to CA, server cert, and server key.
    fn gen_test_certs() -> (tempfile::TempDir, String, String, String) {
        use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let temp_dir = tempfile::TempDir::new().expect("create temp dir");

        // Generate CA
        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        // Generate server certificate
        let server_key = KeyPair::generate().expect("generate server key");
        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        let server_cert = server_params.signed_by(&server_key, &issuer).expect("sign server cert");

        // Write files
        let ca_path = temp_dir.path().join("ca.pem");
        let cert_path = temp_dir.path().join("server.pem");
        let key_path = temp_dir.path().join("server-key.pem");

        std::fs::write(&ca_path, ca_cert.pem()).expect("write CA");
        std::fs::write(&cert_path, server_cert.pem()).expect("write cert");
        std::fs::write(&key_path, server_key.serialize_pem()).expect("write key");

        (
            temp_dir,
            ca_path.to_str().unwrap().to_owned(),
            cert_path.to_str().unwrap().to_owned(),
            key_path.to_str().unwrap().to_owned(),
        )
    }

    /// Install crypto provider for rustls (required for tests).
    fn ensure_crypto_provider() {
        praxis_tls::provider::install();
    }

    #[test]
    fn static_config_single_cert() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, _ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert.clone(),
                key_path: key.clone(),
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: Some(false),
            min_version: None,
        };

        let (settings, shutdown_tx) = build_tls_settings(&tls, "127.0.0.1:8443", "TEST", false)?;
        assert!(
            shutdown_tx.is_none(),
            "static config should not return a cert-watcher shutdown sender"
        );

        drop(settings);
        Ok(())
    }

    #[test]
    fn static_config_with_alpn() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, _ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert,
                key_path: key,
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: Some(false),
            min_version: None,
        };

        let (_settings, shutdown_tx) = build_tls_settings(&tls, "127.0.0.1:8443", "HTTP", true)?;
        assert!(
            shutdown_tx.is_none(),
            "static config with HTTP ALPN should not return a cert-watcher shutdown sender"
        );
        Ok(())
    }

    #[test]
    fn static_config_multi_cert_disables_hot_reload() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, _ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![
                CertKeyPair {
                    cert_path: cert.clone(),
                    key_path: key.clone(),
                    default: false,
                    server_names: vec!["example.com".to_owned()],
                },
                CertKeyPair {
                    cert_path: cert.clone(),
                    key_path: key.clone(),
                    default: true,
                    server_names: vec![],
                },
            ],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: None,
            min_version: None,
        };

        assert!(!tls.is_hot_reload(), "a multi-cert config must disable hot-reload");

        let (_settings, shutdown_tx) = build_tls_settings(&tls, "127.0.0.1:8443", "HTTP", true)?;
        assert!(
            shutdown_tx.is_none(),
            "a multi-cert config should use the static path and not return a shutdown sender"
        );
        Ok(())
    }

    #[test]
    fn static_config_with_client_ca() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert,
                key_path: key,
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: Some(CaConfig {
                ca_path: ca,
                crl_paths: vec![],
            }),
            client_cert_mode: ClientCertMode::Request,
            trusted_spiffe_ids: vec![],
            hot_reload: Some(false),
            min_version: None,
        };

        let (_settings, shutdown_tx) = build_tls_settings(&tls, "127.0.0.1:8443", "mTLS", false)?;
        assert!(
            shutdown_tx.is_none(),
            "static mTLS config should not return a cert-watcher shutdown sender"
        );
        Ok(())
    }

    #[test]
    fn static_config_invalid_cert_path() {
        ensure_crypto_provider();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/nonexistent/cert.pem".to_owned(),
                key_path: "/nonexistent/key.pem".to_owned(),
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: Some(false),
            min_version: None,
        };

        assert!(
            matches!(
                build_tls_settings(&tls, "127.0.0.1:8443", "TEST", false),
                Err(ProxyError::Config(msg)) if msg.contains("127.0.0.1:8443")
            ),
            "an invalid cert path should fail with a config error naming the listener address 127.0.0.1:8443"
        );
    }

    #[test]
    #[cfg(not(feature = "config-reload"))]
    fn hot_reload_without_feature_warns_and_uses_static() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, _ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert,
                key_path: key,
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: None,
            min_version: None,
        };

        assert!(
            tls.is_hot_reload(),
            "a single cert with hot_reload=None should default to hot-reload"
        );

        let (_settings, shutdown_tx) = build_tls_settings(&tls, "127.0.0.1:8443", "HTTP", true)?;
        assert!(
            shutdown_tx.is_none(),
            "without the config-reload feature the builder should fall back to a static config and not return a watcher"
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "config-reload")]
    fn hot_reload_with_feature_spawns_watcher() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, _ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert,
                key_path: key,
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: None,
            min_version: None,
        };

        assert!(tls.is_hot_reload(), "a single cert should enable hot-reload by default");

        let (_settings, shutdown_tx) = build_tls_settings(&tls, "127.0.0.1:8443", "HTTP", true)?;
        assert!(
            shutdown_tx.is_some(),
            "with the config-reload feature the builder should return a cert-watcher shutdown sender"
        );

        if let Some(tx) = shutdown_tx {
            let _ = tx.send(true);
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "config-reload")]
    fn hot_reload_with_client_ca() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert,
                key_path: key,
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: Some(CaConfig {
                ca_path: ca,
                crl_paths: vec![],
            }),
            client_cert_mode: ClientCertMode::Require,
            trusted_spiffe_ids: vec![],
            hot_reload: None,
            min_version: None,
        };

        let (_settings, shutdown_tx) = build_tls_settings(&tls, "127.0.0.1:8443", "mTLS", false)?;
        assert!(
            shutdown_tx.is_some(),
            "hot-reload with a client CA should spawn a watcher and return a shutdown sender"
        );

        if let Some(tx) = shutdown_tx {
            let _ = tx.send(true);
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "config-reload")]
    fn hot_reload_without_client_ca() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, _ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert,
                key_path: key,
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: None,
            min_version: None,
        };

        let (_settings, shutdown_tx) = build_tls_settings(&tls, "127.0.0.1:8443", "HTTP", true)?;
        assert!(
            shutdown_tx.is_some(),
            "hot-reload without a client CA should still spawn a watcher and return a shutdown sender"
        );

        if let Some(tx) = shutdown_tx {
            let _ = tx.send(true);
        }
        Ok(())
    }

    #[test]
    fn context_label_used_in_logging() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, _ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert.clone(),
                key_path: key.clone(),
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: Some(false),
            min_version: None,
        };

        build_tls_settings(&tls, "127.0.0.1:8443", "HTTP", true)?;
        build_tls_settings(&tls, "127.0.0.1:8443", "TCP", false)?;
        build_tls_settings(&tls, "127.0.0.1:8443", "CUSTOM", false)?;
        Ok(())
    }

    #[test]
    fn address_included_in_error_message() {
        ensure_crypto_provider();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/nonexistent/cert.pem".to_owned(),
                key_path: "/nonexistent/key.pem".to_owned(),
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: Some(false),
            min_version: None,
        };

        assert!(
            matches!(
                build_tls_settings(&tls, "192.168.1.1:443", "HTTP", false),
                Err(ProxyError::Config(msg)) if msg.contains("192.168.1.1:443")
            ),
            "the config error should name the failing listener address 192.168.1.1:443"
        );

        assert!(
            matches!(
                build_tls_settings(&tls, "[::1]:8443", "TCP", false),
                Err(ProxyError::Config(msg)) if msg.contains("[::1]:8443")
            ),
            "the config error should name the failing IPv6 listener address [::1]:8443"
        );
    }

    #[test]
    fn alpn_variation_coverage() -> Result<(), ProxyError> {
        ensure_crypto_provider();
        let (_temp, _ca, cert, key) = gen_test_certs();

        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: cert,
                key_path: key,
                default: false,
                server_names: vec![],
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            trusted_spiffe_ids: vec![],
            hot_reload: Some(false),
            min_version: None,
        };

        build_tls_settings(&tls, "127.0.0.1:8443", "HTTP", true)?;
        build_tls_settings(&tls, "127.0.0.1:8443", "TCP", false)?;
        Ok(())
    }
}
