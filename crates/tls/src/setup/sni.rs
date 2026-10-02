// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! SNI-based certificate resolver for multi-cert listeners.

use std::sync::Arc;

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use super::loader;
use crate::{CertKeyPair, SniMatcher, SniMatcherError, TlsError, WildcardMatch};

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
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
#[cfg_attr(
    not(feature = "bench-utils"),
    expect(unreachable_pub, reason = "private without bench-utils")
)]
pub struct SniCertResolver {
    /// SNI-to-certificate matcher, using single-label wildcard semantics.
    matcher: SniMatcher<Arc<CertifiedKey>>,

    /// Fallback certificate when SNI does not match any entry.
    default: Option<Arc<CertifiedKey>>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver")
            .field("hostnames", &self.matcher.exact_names().collect::<Vec<_>>())
            .field("wildcards", &self.matcher.wildcard_patterns())
            .field("has_default", &self.default.is_some())
            .finish()
    }
}

#[cfg(test)]
impl SniCertResolver {
    /// Number of exact hostname-to-certificate mappings.
    fn hostname_count(&self) -> usize {
        self.matcher.exact_names().count()
    }

    /// Number of wildcard suffix mappings.
    fn wildcard_count(&self) -> usize {
        self.matcher.wildcard_patterns().len()
    }

    /// Whether the resolver contains an exact mapping for `hostname`.
    fn has_hostname(&self, hostname: &str) -> bool {
        self.matcher.exact_names().any(|name| name == hostname)
    }

    /// Whether a default (fallback) certificate is configured.
    fn has_default(&self) -> bool {
        self.default.is_some()
    }

    /// Whether the resolver has a wildcard mapping for `domain`.
    ///
    /// `domain` is the suffix after the wildcard label, e.g. `example.com`
    /// for the pattern `*.example.com`.
    fn has_wildcard_for(&self, domain: &str) -> bool {
        self.matcher
            .wildcard_patterns()
            .iter()
            .any(|pattern| pattern == &format!("*.{domain}"))
    }
}

impl SniCertResolver {
    /// Look up a certificate by SNI hostname.
    ///
    /// Used by the [`ResolvesServerCert`] impl, tests, and benchmarks
    /// without constructing a [`ClientHello`]. The method is externally
    /// available when `bench-utils` exposes the module.
    ///
    /// [`ResolvesServerCert`]: rustls::server::ResolvesServerCert
    /// [`ClientHello`]: rustls::server::ClientHello
    #[cfg_attr(
        not(feature = "bench-utils"),
        expect(unreachable_pub, reason = "private without bench-utils")
    )]
    pub fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        sni.and_then(|sni| self.matcher.lookup(sni))
            .or(self.default.as_ref())
            .map(Arc::clone)
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(client_hello.server_name())
    }
}

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

/// Build an [`SniCertResolver`] from a list of certificate entries.
///
/// The entry with `default: true` becomes the fallback certificate.
/// If no entry has `default: true`, unmatched SNI is rejected
/// (the resolver returns `None`).
///
/// # Errors
///
/// Returns an error if certificate loading fails or if duplicate server names are registered.
/// Loads each certificate, then hands the `(server_name, cert)` pairs to a
/// single-label [`SniMatcher`]. The function is externally available when
/// `bench-utils` exposes the module.
#[cfg_attr(
    not(feature = "bench-utils"),
    expect(unreachable_pub, reason = "private without bench-utils")
)]
pub fn build_sni_resolver(certificates: &[CertKeyPair]) -> Result<SniCertResolver, TlsError> {
    let mut entries: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
    let mut default: Option<Arc<CertifiedKey>> = None;

    for pair in certificates {
        let certified = Arc::new(loader::load_certified_key(pair)?);

        if pair.default {
            default = Some(Arc::clone(&certified));
        }

        for name in &pair.server_names {
            entries.push((name.clone(), Arc::clone(&certified)));
        }
    }

    let matcher = SniMatcher::build(entries, WildcardMatch::SingleLabel).map_err(|err| match err {
        SniMatcherError::DuplicatePattern { pattern } => TlsError::DuplicateServerName {
            path: duplicate_cert_path(certificates, &pattern),
            name: pattern,
        },
        SniMatcherError::InvalidPattern { pattern, source } => TlsError::ServerConfigError {
            detail: format!("server_names '{pattern}': {source}"),
        },
    })?;

    tracing::info!(
        exact = matcher.exact_names().count(),
        wildcards = matcher.wildcard_patterns().len(),
        has_default = default.is_some(),
        "SNI certificate resolver configured"
    );

    Ok(SniCertResolver { matcher, default })
}

/// Find the certificate path that introduced a duplicate `server_name`.
///
/// Returns the path of the second certificate to carry `pattern` (matching the
/// previous "the duplicate is the later entry" attribution). Comparison is
/// case-insensitive, mirroring the matcher.
fn duplicate_cert_path(certificates: &[CertKeyPair], pattern: &str) -> String {
    let target = pattern.to_ascii_lowercase();
    let mut seen = false;
    for pair in certificates {
        for name in &pair.server_names {
            if name.to_ascii_lowercase() == target {
                if seen {
                    return pair.cert_path.clone();
                }
                seen = true;
            }
        }
    }
    certificates
        .first()
        .map_or_else(String::new, |pair| pair.cert_path.clone())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::as_conversions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]
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

    // -------------------------------------------------------------------------
    // resolve() / lookup() Tests
    // -------------------------------------------------------------------------

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

    #[test]
    fn resolve_wildcard_rejects_empty_label() {
        let certs = gen_test_certs_with_sans(vec!["*.example.com".to_owned()]);
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: vec!["*.example.com".to_owned()],
        }];
        let resolver = build_sni_resolver(&certificates).unwrap();
        assert!(
            resolver.lookup(Some(".example.com")).is_none(),
            "an empty subdomain label must NOT match *.example.com"
        );
    }

    #[test]
    fn resolve_wildcard_case_insensitive_match() {
        let certs = gen_test_certs_with_sans(vec!["*.example.com".to_owned()]);
        let certificates = vec![CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: vec!["*.example.com".to_owned()],
        }];
        let resolver = build_sni_resolver(&certificates).unwrap();
        assert!(
            resolver.lookup(Some("APP.Example.COM")).is_some(),
            "mixed-case SNI should match the wildcard case-insensitively"
        );
    }

    // -------------------------------------------------------------------------
    // Construction Tests
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

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

    mod properties {
        use std::sync::LazyLock;

        use proptest::prelude::*;

        use super::*;

        /// Shared resolver with distinct certs for the exact name
        /// `api.example.com` and the wildcard `*.example.com`, plus
        /// the pointers of each certificate for identity checks.
        ///
        /// Built once: test certificate generation is too slow to
        /// repeat per proptest case.
        static RESOLVER: LazyLock<(SniCertResolver, usize, usize)> = LazyLock::new(|| {
            let exact_certs = gen_test_certs_with_sans(vec!["api.example.com".to_owned()]);
            let wildcard_certs = gen_test_certs_with_sans(vec!["*.example.com".to_owned()]);
            let certificates = vec![
                CertKeyPair {
                    cert_path: exact_certs.cert_path.to_str().expect("path").to_owned(),
                    default: false,
                    key_path: exact_certs.key_path.to_str().expect("path").to_owned(),
                    server_names: vec!["api.example.com".to_owned()],
                },
                CertKeyPair {
                    cert_path: wildcard_certs.cert_path.to_str().expect("path").to_owned(),
                    default: false,
                    key_path: wildcard_certs.key_path.to_str().expect("path").to_owned(),
                    server_names: vec!["*.example.com".to_owned()],
                },
            ];
            let resolver = build_sni_resolver(&certificates).expect("resolver build");
            // Derive the certificate identities through the public lookup:
            // the exact name yields the exact cert, a single-level subdomain
            // yields the wildcard cert.
            let exact_cert = resolver.lookup(Some("api.example.com")).expect("exact cert");
            let exact_ptr = Arc::as_ptr(&exact_cert) as usize;
            let wildcard_cert = resolver.lookup(Some("other.example.com")).expect("wildcard cert");
            let wildcard_ptr = Arc::as_ptr(&wildcard_cert) as usize;
            (resolver, exact_ptr, wildcard_ptr)
        });

        /// Strategy for a single DNS label.
        fn label() -> impl Strategy<Value = String> {
            "[a-z][a-z0-9]{0,10}"
        }

        proptest! {
            #[test]
            fn exact_beats_wildcard(upper in proptest::bool::ANY) {
                let (resolver, exact_ptr, _) = &*RESOLVER;
                let sni = if upper { "API.EXAMPLE.COM" } else { "api.example.com" };
                let resolved = resolver.lookup(Some(sni)).expect("exact match");
                prop_assert_eq!(Arc::as_ptr(&resolved) as usize, *exact_ptr);
            }

            #[test]
            fn wildcard_matches_single_level(sub in label()) {
                prop_assume!(sub != "api");
                let (resolver, _, wildcard_ptr) = &*RESOLVER;
                let sni = format!("{sub}.example.com");
                let resolved = resolver.lookup(Some(&sni)).expect("wildcard match");
                prop_assert_eq!(Arc::as_ptr(&resolved) as usize, *wildcard_ptr);
            }

            #[test]
            fn wildcard_does_not_cross_labels(first in label(), second in label()) {
                let (resolver, _, _) = &*RESOLVER;
                let sni = format!("{first}.{second}.example.com");
                prop_assert!(resolver.lookup(Some(&sni)).is_none());
            }

            #[test]
            fn bare_domain_does_not_match_wildcard(_dummy in proptest::bool::ANY) {
                let (resolver, _, _) = &*RESOLVER;
                prop_assert!(resolver.lookup(Some("example.com")).is_none());
            }
        }
    }
}
