// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! SNI-based certificate resolver for multi-cert listeners.

use std::{collections::HashMap, sync::Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use super::loader;
use crate::{CertKeyPair, TlsError};

// -----------------------------------------------------------------------------
// SNI Certificate Resolver
// -----------------------------------------------------------------------------

/// Selects a TLS certificate based on the client's SNI hostname.
///
/// Maps each `server_names` entry to its [`CertifiedKey`]. Requests
/// whose SNI matches a registered hostname get that certificate;
/// all others receive the certificate marked `default: true`. If
/// no entry is marked `default: true`, unmatched SNI is rejected.
///
/// ```ignore
/// let resolver = SniCertResolver { certs, default };
/// // rustls calls resolver.resolve(client_hello) during handshake
/// ```
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
pub(crate) struct SniCertResolver {
    /// Hostname-to-certificate mapping.
    certs: HashMap<String, Arc<CertifiedKey>>,

    /// Fallback certificate when SNI does not match any entry.
    default: Option<Arc<CertifiedKey>>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver")
            .field("hostnames", &self.certs.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
impl SniCertResolver {
    /// Number of hostname-to-certificate mappings.
    fn hostname_count(&self) -> usize {
        self.certs.len()
    }

    /// Whether the resolver contains a mapping for `hostname`.
    fn has_hostname(&self, hostname: &str) -> bool {
        self.certs.contains_key(hostname)
    }

    /// Whether a default (fallback) certificate is configured.
    fn has_default(&self) -> bool {
        self.default.is_some()
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name();
        sni.and_then(|name| self.certs.get(&name.to_ascii_lowercase()))
            .cloned()
            .or_else(|| self.default.as_ref().map(Arc::clone))
    }
}

/// Build an [`SniCertResolver`] from a list of certificate entries.
///
/// The entry with `default: true` becomes the fallback certificate.
/// If no entry has `default: true`, unmatched SNI is rejected
/// (the resolver returns `None`).
pub(super) fn build_sni_resolver(certificates: &[CertKeyPair]) -> Result<SniCertResolver, TlsError> {
    let mut certs = HashMap::new();
    let mut default: Option<Arc<CertifiedKey>> = None;

    for pair in certificates {
        let certified = loader::load_certified_key(pair)?;
        let certified = Arc::new(certified);

        if pair.default {
            default = Some(Arc::clone(&certified));
        }

        for name in &pair.server_names {
            let lower = name.to_ascii_lowercase();
            if certs.contains_key(&lower) {
                return Err(TlsError::FileLoadError {
                    path: pair.cert_path.clone(),
                    detail: format!("duplicate server_name '{lower}'; each hostname may only appear once"),
                });
            }
            certs.insert(lower, Arc::clone(&certified));
        }
    }

    tracing::info!(
        hostnames = certs.len(),
        has_default = default.is_some(),
        "SNI certificate resolver configured"
    );

    Ok(SniCertResolver { certs, default })
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
    fn sni_resolver_returns_matching_cert() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                default: false,
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: vec!["known.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                default: true,
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: Vec::new(),
            },
        ];

        let resolver = build_sni_resolver(&certificates).expect("SNI resolver build should succeed");
        assert!(
            resolver.has_hostname("known.example.com"),
            "resolver should contain the registered hostname"
        );
        assert_eq!(
            resolver.hostname_count(),
            1,
            "resolver should have exactly one SNI entry"
        );
    }

    #[test]
    fn sni_resolver_rejects_duplicate_server_name() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                default: false,
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: vec!["api.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                default: false,
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: vec!["api.example.com".to_owned()],
            },
        ];

        let err = build_sni_resolver(&certificates).unwrap_err();
        assert!(
            err.to_string().contains("duplicate server_name"),
            "should reject duplicate server_names: {err}"
        );
    }

    #[test]
    fn sni_resolver_returns_default_for_unknown() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                default: false,
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: vec!["known.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                default: true,
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: Vec::new(),
            },
        ];

        let resolver = build_sni_resolver(&certificates).expect("SNI resolver build should succeed");
        assert!(
            !resolver.has_hostname("unknown.example.com"),
            "unknown hostname should not be in resolver map"
        );
        assert!(
            resolver.has_hostname("known.example.com"),
            "known hostname should be in resolver map"
        );
    }

    #[test]
    fn sni_resolver_default_used_regardless_of_position() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                default: true,
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: Vec::new(),
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                default: false,
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: vec!["api.example.com".to_owned()],
            },
        ];

        let resolver = build_sni_resolver(&certificates).expect("SNI resolver build should succeed");
        assert_eq!(
            resolver.hostname_count(),
            1,
            "resolver should have exactly one SNI entry"
        );
        assert!(
            resolver.has_hostname("api.example.com"),
            "resolver should contain api.example.com"
        );
    }

    #[test]
    fn sni_resolver_no_default_has_no_fallback() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                default: false,
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: vec!["alpha.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                default: false,
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: vec!["beta.example.com".to_owned()],
            },
        ];

        let resolver = build_sni_resolver(&certificates).expect("SNI resolver build should succeed");
        assert_eq!(resolver.hostname_count(), 2, "resolver should have two SNI entries");
        assert!(
            !resolver.has_default(),
            "no default should be set when no entry has default: true"
        );
    }
}
