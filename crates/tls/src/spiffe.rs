// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! SPIFFE identity read and validated from a certificate.
//!
//! One home for the SPIFFE domain logic. A SPIFFE certificate names its bearer
//! with exactly one URI SAN. The listener validates the whole X.509-SVID leaf
//! against the standard's section 5.2 rules and authorizes a peer whose identity
//! is in an allowlist (`svid_id_allowed`).

use std::sync::Arc;

use x509_parser::{certificate::X509Certificate, extensions::GeneralName, prelude::FromDer as _};

/// The URI subject alternative names of an already-parsed certificate (the
/// `SubjectAltName` extension, RFC 5280 section 4.2.1.6).
pub(crate) fn uri_sans<'cert>(cert: &'cert X509Certificate<'cert>) -> impl Iterator<Item = &'cert str> {
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .into_iter()
        .flat_map(|san| san.value.general_names.iter())
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            GeneralName::OtherName(..)
            | GeneralName::RFC822Name(_)
            | GeneralName::DNSName(_)
            | GeneralName::X400Address(_)
            | GeneralName::DirectoryName(_)
            | GeneralName::EDIPartyName(_)
            | GeneralName::IPAddress(_)
            | GeneralName::RegisteredID(_)
            | GeneralName::Invalid(..) => None,
        })
}

/// Whether `leaf_der` encodes a valid X.509-SVID leaf whose SPIFFE ID is a
/// member of `allowed`. An empty `allowed` accepts any valid SVID leaf.
///
/// The handshake authorization floor: the section 5.2 leaf validation
/// [`validated_svid_id`] performs, plus an exact-string allowlist check over the
/// whole SPIFFE ID (trust domain included). A parse failure or unmet rule returns
/// `false`, so it fails closed.
pub(crate) fn svid_id_allowed(leaf_der: &[u8], allowed: &[Arc<str>]) -> bool {
    let Ok((_, cert)) = X509Certificate::from_der(leaf_der) else {
        return false;
    };
    let Some(id) = validated_svid_id(&cert) else {
        return false;
    };
    allowed.is_empty() || allowed.iter().any(|a| a.as_ref() == id)
}

/// The SPIFFE ID borrowed from a parsed certificate, if it is a valid X.509-SVID
/// leaf, else `None`.
///
/// Enforces the SPIFFE X509-SVID standard (standards/X509-SVID.md) section 5.2
/// leaf rules a chain check does not: exactly one URI SAN that is a valid SPIFFE
/// ID, `basicConstraints` cA false, and `keyUsage` without keyCertSign or
/// cRLSign. A malformed extension or unmet rule yields `None` (fail closed). The
/// serverAuth EKU, chain, and validity are the caller's trust-anchor check.
fn validated_svid_id<'cert>(cert: &'cert X509Certificate<'cert>) -> Option<&'cert str> {
    if has_unusable_extension(cert) {
        return None;
    }
    // X509-SVID 4.1: reject a leaf whose basicConstraints sets cA true. A malformed
    // extension rejects, an absent one is permissive per the RFC 5280 default.
    match cert.basic_constraints() {
        Ok(Some(bc)) if bc.value.ca => return None,
        Err(_) => return None,
        _ => {},
    }
    // X509-SVID 4.3: reject a leaf whose keyUsage sets keyCertSign or cRLSign.
    match cert.key_usage() {
        Ok(Some(ku)) if ku.value.key_cert_sign() || ku.value.crl_sign() => return None,
        Err(_) => return None,
        _ => {},
    }
    // X509-SVID 3.1: exactly one URI SAN, and it must be a valid leaf SPIFFE ID.
    let mut uris = uri_sans(cert);
    let id = uris.next()?;
    if uris.next().is_some() || !is_leaf_spiffe_id(id) {
        return None;
    }
    Some(id)
}

/// Whether the certificate carries an extension the verifier cannot honor.
///
/// Rejects a known extension that failed to parse, such as a malformed
/// basicConstraints that x509-parser would otherwise report as absent, and any
/// unrecognized critical extension (RFC 5280 section 4.2). An unrecognized
/// non-critical extension is ignored, as RFC 5280 allows.
fn has_unusable_extension(cert: &X509Certificate<'_>) -> bool {
    use x509_parser::extensions::ParsedExtension;

    cert.extensions().iter().any(|ext| {
        let parsed = ext.parsed_extension();
        matches!(parsed, ParsedExtension::ParseError { .. })
            || (ext.critical && matches!(parsed, ParsedExtension::UnsupportedExtension { .. }))
    })
}

/// Whether `id` is a valid leaf SPIFFE ID: a valid SPIFFE ID by the SPIFFE-ID
/// spec (scheme, trust-domain and path grammar parsed by the `spiffe` crate) with
/// a non-empty path, so it names a workload rather than the trust domain root
/// (X509-SVID section 3.1).
///
/// The shared validity floor: the server pins one exact id, the client accepts
/// any valid name.
///
/// The `spiffe` parser follows RFC 3986 case-insensitive schemes and accepts an
/// uppercase `SPIFFE://`. Requiring the canonical lowercase scheme keeps the
/// accepted set equal to the exact-byte pin the server compares against.
pub(crate) fn is_leaf_spiffe_id(id: &str) -> bool {
    id.starts_with("spiffe://") && id.parse::<spiffe::SpiffeId>().is_ok_and(|sid| !sid.path().is_empty())
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    /// Build a self-signed leaf carrying the given URI SANs.
    fn leaf_with_uri_sans(uris: &[&str]) -> Vec<u8> {
        use rcgen::{CertificateParams, DnType, KeyPair, SanType};

        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, "peer");
        for uri in uris {
            params
                .subject_alt_names
                .push(SanType::URI((*uri).try_into().expect("uri san")));
        }
        params.self_signed(&key).expect("self signed").der().to_vec()
    }

    #[test]
    fn a_two_uri_san_leaf_names_nobody() {
        let der = leaf_with_uri_sans(&["spiffe://grid.internal/site/a", "spiffe://grid.internal/site/b"]);
        assert!(
            !svid_id_allowed(&der, &[]),
            "a multi-SAN leaf names nobody and is not a valid SVID"
        );
    }

    // ---- SVID leaf validation (X509-SVID section 5.2) ----

    const EXPECTED: &str = "spiffe://grid.internal/signals";

    /// A self-signed leaf with the given SPIFFE URI SAN and leaf constraints, to
    /// exercise the section 5.2 rules directly.
    fn svid_leaf(uri: Option<&str>, ca: bool, key_cert_sign: bool) -> Vec<u8> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};

        let key = KeyPair::generate().expect("key");
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name.push(DnType::CommonName, "peer");
        if let Some(u) = uri {
            p.subject_alt_names.push(SanType::URI(u.try_into().expect("uri san")));
        }
        if ca {
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        if key_cert_sign {
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        }
        p.self_signed(&key).expect("self signed").der().to_vec()
    }

    #[test]
    fn a_valid_svid_is_accepted() {
        let der = svid_leaf(Some(EXPECTED), false, false);
        assert!(svid_id_allowed(&der, &[Arc::from(EXPECTED)]));
    }

    #[test]
    fn a_ca_flagged_leaf_is_rejected() {
        let der = svid_leaf(Some(EXPECTED), true, false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_key_cert_sign_leaf_is_rejected() {
        let der = svid_leaf(Some(EXPECTED), false, true);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_non_spiffe_uri_is_rejected() {
        let der = svid_leaf(Some("https://grid.internal/signals"), false, false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_leaf_without_a_uri_san_is_rejected() {
        let der = svid_leaf(None, false, false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_multi_segment_path_is_accepted() {
        let id = "spiffe://grid.internal/site/pool-a/node-1";
        let der = svid_leaf(Some(id), false, false);
        assert!(svid_id_allowed(&der, &[Arc::from(id)]));
    }

    /// A leaf with a present-but-unparseable basicConstraints (a bare NULL where a
    /// SEQUENCE belongs), critical or not. rcgen cannot emit this, so it is
    /// hand-built.
    fn leaf_with_malformed_bc(critical: bool) -> Vec<u8> {
        use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair, SanType};

        let key = KeyPair::generate().expect("key");
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name.push(DnType::CommonName, "peer");
        p.subject_alt_names
            .push(SanType::URI(EXPECTED.try_into().expect("uri")));
        let mut bc = CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x05, 0x00]);
        bc.set_criticality(critical);
        p.custom_extensions.push(bc);
        p.self_signed(&key).expect("self signed").der().to_vec()
    }

    #[test]
    fn a_malformed_basic_constraints_is_rejected_critical_or_not() {
        // A known extension that failed to parse must not read as absent-permissive.
        assert!(!svid_id_allowed(&leaf_with_malformed_bc(true), &[]));
        assert!(!svid_id_allowed(&leaf_with_malformed_bc(false), &[]));
    }

    #[test]
    fn an_empty_allowlist_accepts_a_valid_leaf() {
        assert!(svid_id_allowed(&svid_leaf(Some(EXPECTED), false, false), &[]));
    }

    #[test]
    fn an_empty_allowlist_rejects_a_non_svid_leaf() {
        assert!(!svid_id_allowed(&svid_leaf(Some(EXPECTED), true, false), &[]));
        assert!(!svid_id_allowed(
            &svid_leaf(Some("https://grid.internal/x"), false, false),
            &[]
        ));
    }

    #[test]
    fn spiffe_id_shape_rules_accept_and_reject() {
        assert!(is_leaf_spiffe_id("spiffe://example.org/workload"));
        assert!(is_leaf_spiffe_id("spiffe://example.org/site/pool-a/node-1"));
        for bad in [
            "spiffe://example.org",            // no path
            "spiffe://example.org/",           // empty path
            "spiffe:///workload",              // empty trust domain
            "https://example.org/workload",    // wrong scheme
            "SPIFFE://example.org/workload",   // parser normalizes case, lowercase guard rejects
            "spiffe://example.org/work\nload", // control byte
            "spiffe://example.org/work\0load", // NUL byte
            " spiffe://example.org/workload",  // leading space, no prefix match
            "spiffe://",                       // nothing
            "",                                // empty
        ] {
            assert!(!is_leaf_spiffe_id(bad), "must reject {bad:?}");
        }
    }

    #[test]
    fn allowed_accepts_a_listed_id() {
        let der = svid_leaf(Some(EXPECTED), false, false);
        let allow: [Arc<str>; 2] = [Arc::from("spiffe://grid.internal/other"), Arc::from(EXPECTED)];
        assert!(svid_id_allowed(&der, &allow));
    }

    #[test]
    fn allowed_rejects_an_unlisted_id() {
        let der = svid_leaf(Some(EXPECTED), false, false);
        let allow: [Arc<str>; 1] = [Arc::from("spiffe://grid.internal/other")];
        assert!(!svid_id_allowed(&der, &allow), "an id not in the allowlist is rejected");
    }

    #[test]
    fn an_empty_allowlist_accepts_any_valid_svid() {
        let der = svid_leaf(Some(EXPECTED), false, false);
        assert!(svid_id_allowed(&der, &[]), "empty allowlist accepts any valid leaf");
    }

    #[test]
    fn allowed_rejects_an_invalid_leaf_even_when_listed() {
        // A CA-flagged leaf is not a valid SVID, so membership cannot rescue it.
        let der = svid_leaf(Some(EXPECTED), true, false);
        let allow: [Arc<str>; 1] = [Arc::from(EXPECTED)];
        assert!(!svid_id_allowed(&der, &allow));
    }
}
