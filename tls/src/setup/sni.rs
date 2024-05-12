// SPDX-License-Identifier: LGPL-3.0-only
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
/// all others get the default certificate.
///
/// ```ignore
/// let resolver = SniCertResolver { certs, default };
/// // rustls calls resolver.resolve(client_hello) during handshake
/// ```
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
pub(crate) struct SniCertResolver {
    /// Hostname-to-certificate mapping.
    pub(super) certs: HashMap<String, Arc<CertifiedKey>>,

    /// Fallback certificate when SNI does not match any entry.
    default: Arc<CertifiedKey>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver")
            .field("hostnames", &self.certs.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name();
        let cert = sni
            .and_then(|name| self.certs.get(&name.to_lowercase()))
            .cloned()
            .unwrap_or_else(|| Arc::clone(&self.default));
        Some(cert)
    }
}

/// Build an [`SniCertResolver`] from a list of certificate entries.
///
/// The first entry without `server_names` (or the first entry if all
/// have `server_names`) becomes the default certificate.
#[allow(clippy::expect_used, reason = "map guaranteed non-empty")]
#[allow(clippy::too_many_lines, reason = "validation logic is sequential")]
pub(super) fn build_sni_resolver(certificates: &[CertKeyPair]) -> Result<SniCertResolver, TlsError> {
    let mut certs = HashMap::new();
    let mut default: Option<Arc<CertifiedKey>> = None;

    for pair in certificates {
        let certified = loader::load_certified_key(pair)?;
        let certified = Arc::new(certified);

        if pair.server_names.is_empty() {
            if default.is_some() {
                return Err(TlsError::FileLoadError {
                    path: pair.cert_path.clone(),
                    detail: "multiple certificates have empty server_names; only one default certificate is allowed"
                        .to_owned(),
                });
            }
            default = Some(Arc::clone(&certified));
        } else {
            for name in &pair.server_names {
                let lower = name.to_lowercase();
                if certs.contains_key(&lower) {
                    return Err(TlsError::FileLoadError {
                        path: pair.cert_path.clone(),
                        detail: format!("duplicate server_name '{lower}'; each hostname may only appear once"),
                    });
                }
                certs.insert(lower, Arc::clone(&certified));
            }
        }
    }

    let default =
        default.unwrap_or_else(|| Arc::clone(certs.values().next().expect("at least one certificate required")));

    tracing::info!(hostnames = certs.len(), "SNI certificate resolver configured");

    Ok(SniCertResolver { certs, default })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{super::tests::gen_test_certs, *};

    #[test]
    fn sni_resolver_returns_matching_cert() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: vec!["known.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: Vec::new(),
            },
        ];

        let resolver = build_sni_resolver(&certificates).expect("SNI resolver build should succeed");
        assert!(
            resolver.certs.contains_key("known.example.com"),
            "resolver should contain the registered hostname"
        );
        assert!(
            resolver.certs.len() == 1,
            "resolver should have exactly one SNI entry, got {}",
            resolver.certs.len()
        );
    }

    #[test]
    fn sni_resolver_rejects_multiple_defaults() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: Vec::new(),
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: Vec::new(),
            },
        ];

        let err = build_sni_resolver(&certificates).unwrap_err();
        assert!(
            err.to_string().contains("only one default"),
            "should reject multiple default certificates: {err}"
        );
    }

    #[test]
    fn sni_resolver_rejects_duplicate_server_name() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: vec!["api.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
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
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: vec!["known.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: Vec::new(),
            },
        ];

        let resolver = build_sni_resolver(&certificates).expect("SNI resolver build should succeed");
        assert!(
            !resolver.certs.contains_key("unknown.example.com"),
            "unknown hostname should not be in resolver map"
        );
        assert!(
            resolver.certs.contains_key("known.example.com"),
            "known hostname should be in resolver map"
        );
    }
}
