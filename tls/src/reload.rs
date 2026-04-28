// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Hot-reloadable TLS certificate resolver.
//!
//! [`ReloadableCertResolver`] wraps an [`ArcSwap<CertifiedKey>`] and
//! implements [`ResolvesServerCert`] so that new TLS handshakes
//! atomically pick up rotated certificates without restarting.
//!
//! [`ReloadableCertResolver`]: crate::reload::ReloadableCertResolver
//! [`ArcSwap<CertifiedKey>`]: arc_swap::ArcSwap
//! [`ResolvesServerCert`]: rustls::server::ResolvesServerCert

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::{CertKeyPair, TlsError, setup::loader};

// -----------------------------------------------------------------------------
// ReloadableCertResolver
// -----------------------------------------------------------------------------

/// Atomically swappable certificate resolver for hot-reload.
///
/// Holds a [`CertifiedKey`] behind an [`ArcSwap`] so that calls to
/// [`reload`] publish a new certificate without blocking in-flight
/// TLS handshakes.
///
/// ```ignore
/// let resolver = ReloadableCertResolver::new(&pair)?;
/// // rustls calls resolver.resolve(client_hello) during handshake
/// resolver.reload(&pair)?; // swap to a new cert atomically
/// ```
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
/// [`ArcSwap`]: arc_swap::ArcSwap
/// [`reload`]: ReloadableCertResolver::reload
pub struct ReloadableCertResolver {
    /// The currently active certified key, atomically swappable.
    current: Arc<ArcSwap<CertifiedKey>>,
}

impl ReloadableCertResolver {
    /// Load the initial certificate and build a resolver.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if the certificate or key cannot be
    /// loaded or parsed.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn new(pair: &CertKeyPair) -> Result<Self, TlsError> {
        let certified = loader::load_certified_key(pair)?;
        Ok(Self {
            current: Arc::new(ArcSwap::from_pointee(certified)),
        })
    }

    /// Reload the certificate from disk, validate, and atomically swap.
    ///
    /// On success the new cert is served to all subsequent TLS
    /// handshakes. On failure the previous cert remains active and
    /// an error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if the new certificate or key cannot be
    /// loaded or parsed.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn reload(&self, pair: &CertKeyPair) -> Result<(), TlsError> {
        let certified = loader::load_certified_key(pair)?;
        self.current.store(Arc::new(certified));
        tracing::info!(
            cert_path = %pair.cert_path,
            "TLS certificate reloaded"
        );
        Ok(())
    }

    /// Return an [`Arc`] handle to the inner [`ArcSwap`] for sharing
    /// with the watcher task.
    ///
    /// [`Arc`]: std::sync::Arc
    /// [`ArcSwap`]: arc_swap::ArcSwap
    pub fn arc(&self) -> Arc<ArcSwap<CertifiedKey>> {
        Arc::clone(&self.current)
    }
}

impl std::fmt::Debug for ReloadableCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableCertResolver")
            .field("has_cert", &true)
            .finish()
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::gen_test_certs;

    #[test]
    fn new_and_resolve_returns_cert() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let resolver = ReloadableCertResolver::new(&pair).expect("resolver creation should succeed");
        let loaded = resolver.current.load_full();
        assert!(!loaded.cert.is_empty(), "resolved cert chain should not be empty");
    }

    #[test]
    fn reload_swaps_certificate() {
        let certs1 = gen_test_certs();
        let pair1 = CertKeyPair {
            cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
            default: false,
            key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
            server_names: Vec::new(),
        };

        let resolver = ReloadableCertResolver::new(&pair1).expect("initial load should succeed");
        let before = resolver.current.load_full();

        let certs2 = gen_test_certs();
        let pair2 = CertKeyPair {
            cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
            default: false,
            key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
            server_names: Vec::new(),
        };

        resolver.reload(&pair2).expect("reload should succeed");
        let after = resolver.current.load_full();

        assert_ne!(
            before.cert[0].as_ref(),
            after.cert[0].as_ref(),
            "reloaded cert should differ from original"
        );
    }

    #[test]
    fn reload_invalid_cert_keeps_old() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let resolver = ReloadableCertResolver::new(&pair).expect("initial load should succeed");
        let before = resolver.current.load_full();

        let bad_pair = CertKeyPair {
            cert_path: "/nonexistent/cert.pem".to_owned(),
            default: false,
            key_path: "/nonexistent/key.pem".to_owned(),
            server_names: Vec::new(),
        };

        let err = resolver.reload(&bad_pair);
        assert!(err.is_err(), "reload with bad path should fail");

        let after = resolver.current.load_full();
        assert_eq!(
            before.cert[0].as_ref(),
            after.cert[0].as_ref(),
            "cert should be unchanged after failed reload"
        );
    }

    #[test]
    fn debug_impl_does_not_panic() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let resolver = ReloadableCertResolver::new(&pair).expect("resolver creation");
        let dbg = format!("{resolver:?}");
        assert!(
            dbg.contains("ReloadableCertResolver"),
            "Debug output should contain struct name"
        );
    }
}
