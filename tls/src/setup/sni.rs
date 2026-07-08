// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
/// Wildcard entries like `*.example.com` match single-level
/// subdomains (e.g. `app.example.com` matches but
/// `a.b.example.com` does not).
///
/// ```ignore
/// let resolver = SniCertResolver { certs, default };
/// // rustls calls resolver.resolve(client_hello) during handshake
/// ```
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
pub(crate) struct SniCertResolver {
    /// Hostname-to-certificate mapping (exact matches).
    certs: HashMap<String, Arc<CertifiedKey>>,

    /// Wildcard subdomain suffix to certificate mapping.
    ///
    /// For `*.example.com`, stores `(".example.com", cert)`.
    /// Only single-level subdomains match.
    wildcard_certs: Vec<(String, Arc<CertifiedKey>)>,

    /// Fallback certificate when SNI does not match any entry.
    default: Option<Arc<CertifiedKey>>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let wildcards: Vec<&str> = self.wildcard_certs.iter().map(|(s, _)| s.as_str()).collect();
        f.debug_struct("SniCertResolver")
            .field("hostnames", &self.certs.keys().collect::<Vec<_>>())
            .field("wildcards", &wildcards)
            .finish()
    }
}

#[cfg(test)]
impl SniCertResolver {
    /// Number of exact hostname-to-certificate mappings.
    fn hostname_count(&self) -> usize {
        self.certs.len()
    }

    /// Number of wildcard suffix mappings.
    fn wildcard_count(&self) -> usize {
        self.wildcard_certs.len()
    }

    /// Whether the resolver contains an exact mapping for `hostname`.
    fn has_hostname(&self, hostname: &str) -> bool {
        self.certs.contains_key(hostname)
    }

    /// Whether a default (fallback) certificate is configured.
    fn has_default(&self) -> bool {
        self.default.is_some()
    }

    /// Whether the resolver has a wildcard mapping for `domain`.
    fn has_wildcard_for(&self, domain: &str) -> bool {
        let suffix = format!(".{domain}");
        self.wildcard_certs.iter().any(|(s, _)| s == &suffix)
    }
}

impl SniCertResolver {
    /// Look up a certificate by SNI hostname.
    ///
    /// This is the core resolution logic used by the
    /// [`ResolvesServerCert`] impl. Extracted so tests can call
    /// it without constructing a [`ClientHello`].
    ///
    /// [`ResolvesServerCert`]: rustls::server::ResolvesServerCert
    /// [`ClientHello`]: rustls::server::ClientHello
    fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let Some(sni) = sni else {
            return self.default.as_ref().map(Arc::clone);
        };
        let lower = sni.to_ascii_lowercase();

        if let Some(cert) = self.certs.get(&lower) {
            return Some(Arc::clone(cert));
        }

        for (suffix, cert) in &self.wildcard_certs {
            if lower.ends_with(suffix.as_str())
                && lower.len() > suffix.len()
                && lower
                    .get(..lower.len() - suffix.len())
                    .is_some_and(|prefix| !prefix.contains('.'))
            {
                return Some(Arc::clone(cert));
            }
        }

        self.default.as_ref().map(Arc::clone)
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(client_hello.server_name())
    }
}

/// Build an [`SniCertResolver`] from a list of certificate entries.
///
/// The entry with `default: true` becomes the fallback certificate.
/// If no entry has `default: true`, unmatched SNI is rejected
/// (the resolver returns `None`).
pub(super) fn build_sni_resolver(certificates: &[CertKeyPair]) -> Result<SniCertResolver, TlsError> {
    let mut certs = HashMap::new();
    let mut wildcard_certs = Vec::new();
    let mut default: Option<Arc<CertifiedKey>> = None;

    for pair in certificates {
        let certified = Arc::new(loader::load_certified_key(pair)?);

        if pair.default {
            default = Some(Arc::clone(&certified));
        }

        register_server_names(pair, &certified, &mut certs, &mut wildcard_certs)?;
    }

    tracing::info!(
        exact = certs.len(),
        wildcards = wildcard_certs.len(),
        has_default = default.is_some(),
        "SNI certificate resolver configured"
    );

    Ok(SniCertResolver {
        certs,
        wildcard_certs,
        default,
    })
}

/// Register server names from a certificate pair into the resolver maps.
fn register_server_names(
    pair: &CertKeyPair,
    certified: &Arc<CertifiedKey>,
    certs: &mut HashMap<String, Arc<CertifiedKey>>,
    wildcard_certs: &mut Vec<(String, Arc<CertifiedKey>)>,
) -> Result<(), TlsError> {
    for name in &pair.server_names {
        let lower = name.to_ascii_lowercase();

        if let Some(suffix) = lower.strip_prefix("*.") {
            let wildcard_suffix = format!(".{suffix}");
            if wildcard_certs.iter().any(|(s, _)| s == &wildcard_suffix) {
                return Err(TlsError::DuplicateServerName {
                    name: format!("*.{suffix}"),
                    path: pair.cert_path.clone(),
                });
            }
            wildcard_certs.push((wildcard_suffix, Arc::clone(certified)));
        } else {
            use std::collections::hash_map::Entry;
            match certs.entry(lower) {
                Entry::Occupied(e) => {
                    return Err(TlsError::DuplicateServerName {
                        name: e.key().clone(),
                        path: pair.cert_path.clone(),
                    });
                },
                Entry::Vacant(e) => {
                    e.insert(Arc::clone(certified));
                },
            }
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::{gen_test_certs, gen_test_certs_with_sans};

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
    fn sni_resolver_wildcard_stored_separately() {
        let certs = gen_test_certs();
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: vec!["*.example.com".to_owned()],
        }];

        let resolver = build_sni_resolver(&certificates).expect("wildcard SNI should build");
        assert_eq!(resolver.hostname_count(), 0, "wildcard should not be in exact map");
        assert_eq!(resolver.wildcard_count(), 1, "wildcard should be in wildcard list");
    }

    #[test]
    fn sni_resolver_multi_domain_cert() {
        let certs = gen_test_certs_with_sans(vec!["api.example.com".to_owned(), "web.example.com".to_owned()]);
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: vec!["api.example.com".to_owned(), "web.example.com".to_owned()],
        }];

        let resolver = build_sni_resolver(&certificates).expect("multi-domain SNI should build");
        assert!(
            resolver.has_hostname("api.example.com"),
            "should resolve api.example.com"
        );
        assert!(
            resolver.has_hostname("web.example.com"),
            "should resolve web.example.com"
        );
        assert_eq!(resolver.hostname_count(), 2, "should have two SNI entries");
    }

    #[test]
    fn sni_resolver_rejects_duplicate_wildcard() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                default: false,
                key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                server_names: vec!["*.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                default: false,
                key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                server_names: vec!["*.example.com".to_owned()],
            },
        ];

        let err = build_sni_resolver(&certificates).unwrap_err();
        assert!(
            err.to_string().contains("duplicate server_name"),
            "should reject duplicate wildcard: {err}"
        );
    }

    #[test]
    fn sni_resolver_wildcard_matches_correct_domain() {
        let certs = gen_test_certs_with_sans(vec!["*.example.com".to_owned()]);
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: vec!["*.example.com".to_owned()],
        }];

        let resolver = build_sni_resolver(&certificates).expect("wildcard SNI should build");
        assert!(
            resolver.has_wildcard_for("example.com"),
            "resolver should have wildcard for example.com"
        );
        assert!(
            !resolver.has_wildcard_for("other.com"),
            "resolver should not have wildcard for other.com"
        );
    }

    // -----------------------------------------------------------------------
    // resolve() / lookup() Tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_exact_hostname_returns_cert() {
        let certs = gen_test_certs();
        let resolver = build_resolver_with_exact(&certs, "api.example.com", false);
        assert!(
            resolver.lookup(Some("api.example.com")).is_some(),
            "exact hostname should resolve"
        );
    }

    #[test]
    fn resolve_unknown_without_default_returns_none() {
        let certs = gen_test_certs();
        let resolver = build_resolver_with_exact(&certs, "api.example.com", false);
        assert!(
            resolver.lookup(Some("unknown.example.com")).is_none(),
            "unknown hostname without default should return None"
        );
    }

    #[test]
    fn resolve_unknown_falls_back_to_default() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let certificates = vec![
            CertKeyPair {
                cert_path: certs1.cert_path.to_str().expect("path").to_owned(),
                default: false,
                key_path: certs1.key_path.to_str().expect("path").to_owned(),
                server_names: vec!["known.example.com".to_owned()],
            },
            CertKeyPair {
                cert_path: certs2.cert_path.to_str().expect("path").to_owned(),
                default: true,
                key_path: certs2.key_path.to_str().expect("path").to_owned(),
                server_names: Vec::new(),
            },
        ];
        let resolver = build_sni_resolver(&certificates).unwrap();
        assert!(
            resolver.lookup(Some("unknown.example.com")).is_some(),
            "unknown hostname should fall back to default"
        );
    }

    #[test]
    fn resolve_no_sni_returns_default() {
        let certs = gen_test_certs();
        let resolver = build_resolver_with_exact(&certs, "example.com", true);
        assert!(resolver.lookup(None).is_some(), "absent SNI should return default cert");
    }

    #[test]
    fn resolve_no_sni_no_default_returns_none() {
        let certs = gen_test_certs();
        let resolver = build_resolver_with_exact(&certs, "example.com", false);
        assert!(
            resolver.lookup(None).is_none(),
            "absent SNI without default should return None"
        );
    }

    #[test]
    fn resolve_case_insensitive_match() {
        let certs = gen_test_certs();
        let resolver = build_resolver_with_exact(&certs, "api.example.com", false);
        assert!(
            resolver.lookup(Some("API.Example.COM")).is_some(),
            "case-insensitive SNI should match"
        );
    }

    #[test]
    fn resolve_wildcard_single_level() {
        let certs = gen_test_certs_with_sans(vec!["*.example.com".to_owned()]);
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: vec!["*.example.com".to_owned()],
        }];
        let resolver = build_sni_resolver(&certificates).unwrap();
        assert!(
            resolver.lookup(Some("app.example.com")).is_some(),
            "single-level subdomain should match *.example.com"
        );
    }

    #[test]
    fn resolve_wildcard_rejects_multi_level() {
        let certs = gen_test_certs_with_sans(vec!["*.example.com".to_owned()]);
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: vec!["*.example.com".to_owned()],
        }];
        let resolver = build_sni_resolver(&certificates).unwrap();
        assert!(
            resolver.lookup(Some("a.b.example.com")).is_none(),
            "multi-level subdomain must NOT match *.example.com"
        );
    }

    #[test]
    fn resolve_wildcard_rejects_bare_domain() {
        let certs = gen_test_certs_with_sans(vec!["*.example.com".to_owned()]);
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: vec!["*.example.com".to_owned()],
        }];
        let resolver = build_sni_resolver(&certificates).unwrap();
        assert!(
            resolver.lookup(Some("example.com")).is_none(),
            "bare domain must NOT match *.example.com"
        );
    }

    // -----------------------------------------------------------------------
    // Construction Tests
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    /// Build a resolver with a single exact hostname mapping.
    fn build_resolver_with_exact(
        certs: &crate::test_utils::TestCerts,
        hostname: &str,
        default: bool,
    ) -> SniCertResolver {
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: vec![hostname.to_owned()],
        }];
        build_sni_resolver(&certificates).unwrap()
    }
}
