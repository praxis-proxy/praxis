// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! SPIFFE identity read and validated from a certificate.
//!
//! One home for the SPIFFE domain logic. A SPIFFE certificate names its bearer
//! with exactly one URI SAN. The listener validates the whole X.509-SVID leaf
//! against the standard (standards/X509-SVID.md) and authorizes a peer whose
//! identity is in an allowlist (`authorize_peer`).

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

/// The outcome of authorizing a peer certificate at the handshake.
///
/// Distinguishes an invalid leaf from an allowlist miss so the caller can log the
/// reason without exposing it on the wire.
#[derive(Debug)]
pub(crate) enum PeerAuth {
    /// A valid X.509-SVID leaf whose SPIFFE ID the allowlist admits.
    Allowed,

    /// The certificate is not a valid X.509-SVID leaf.
    InvalidLeaf,

    /// A valid X.509-SVID leaf whose SPIFFE ID is not in a non-empty allowlist.
    NotAllowed(String),
}

/// Authorize a peer certificate: validate the X.509-SVID leaf, then check the
/// allowlist. An empty `allowed` admits any valid leaf.
///
/// The handshake authorization floor, applied after the chain check. Fails
/// closed: a parse failure or unmet leaf rule is [`PeerAuth::InvalidLeaf`].
pub(crate) fn authorize_peer(leaf_der: &[u8], allowed: &[Arc<str>]) -> PeerAuth {
    let Some(id) = validated_svid_id_from_der(leaf_der) else {
        return PeerAuth::InvalidLeaf;
    };
    if allowed.is_empty() || allowed.iter().any(|a| a.as_ref() == id) {
        PeerAuth::Allowed
    } else {
        PeerAuth::NotAllowed(id)
    }
}

/// The SPIFFE ID of `leaf_der` if it is a valid X.509-SVID leaf, owned so the
/// parsed certificate need not outlive the call. `None` on any parse failure or
/// unmet rule (fail closed).
fn validated_svid_id_from_der(leaf_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    validated_svid_id(&cert).map(ToOwned::to_owned)
}

/// The SPIFFE ID borrowed from a parsed certificate, if it is a valid X.509-SVID
/// leaf, else `None`.
///
/// Enforces the SPIFFE X509-SVID standard (standards/X509-SVID.md) rules a chain
/// check does not. The section 5 validation floor: exactly one URI SAN that is a
/// valid leaf SPIFFE ID, `cA` not true, and neither keyCertSign nor cRLSign. Plus
/// the section 4 leaf profile a conforming SVID carries: a present, critical
/// `keyUsage` with digitalSignature, and, when the `extendedKeyUsage` is present,
/// both serverAuth and clientAuth. A malformed extension or unmet rule yields
/// `None` (fail closed). Chain and validity are the caller's trust-anchor check.
fn validated_svid_id<'cert>(cert: &'cert X509Certificate<'cert>) -> Option<&'cert str> {
    if has_unusable_extension(cert) {
        return None;
    }
    // 4.1 / 5: a leaf MUST NOT set cA true. A malformed extension rejects; an
    // absent one is cA false per the RFC 5280 default.
    match cert.basic_constraints() {
        Ok(Some(bc)) if bc.value.ca => return None,
        Err(_) => return None,
        _ => {},
    }
    // 4.3: keyUsage MUST be present, critical, set digitalSignature, and set
    // neither keyCertSign nor cRLSign.
    let Ok(Some(ku)) = cert.key_usage() else {
        return None;
    };
    if !ku.critical || !ku.value.digital_signature() || ku.value.key_cert_sign() || ku.value.crl_sign() {
        return None;
    }
    // 4.4: when the extendedKeyUsage is present it MUST set both serverAuth and
    // clientAuth. An absent EKU is permitted (the standard marks it SHOULD).
    match cert.extended_key_usage() {
        Ok(Some(eku)) if !(eku.value.server_auth && eku.value.client_auth) => return None,
        Err(_) => return None,
        _ => {},
    }
    // 5: exactly one URI SAN, and it must be a valid leaf SPIFFE ID.
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
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };

    use super::*;

    const EXPECTED: &str = "spiffe://grid.internal/signals";

    // ---- Certificate builders --------------------------------------------------

    /// A self-signed leaf with the given URI SANs, key usages, extended key usages,
    /// and cA flag. Empty `key_usages` / `ekus` omit that extension entirely.
    fn leaf(uris: &[&str], key_usages: &[KeyUsagePurpose], ekus: &[ExtendedKeyUsagePurpose], ca: bool) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name.push(DnType::CommonName, "peer");
        for uri in uris {
            p.subject_alt_names
                .push(SanType::URI((*uri).try_into().expect("uri san")));
        }
        if ca {
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        p.key_usages = key_usages.to_vec();
        p.extended_key_usages = ekus.to_vec();
        p.self_signed(&key).expect("self signed").der().to_vec()
    }

    /// A conforming X.509-SVID leaf: critical keyUsage with digitalSignature, EKU
    /// with serverAuth and clientAuth, no basicConstraints (cA false by default).
    fn conforming(uri: &str) -> Vec<u8> {
        leaf(
            &[uri],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            false,
        )
    }

    /// A leaf carrying a raw extension (OID 2.5.29.x content) plus a conforming
    /// keyUsage, to exercise one malformed or non-standard extension in isolation.
    fn leaf_with_custom_ext(uri: &str, ext: CustomExtension, with_key_usage: bool) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name.push(DnType::CommonName, "peer");
        p.subject_alt_names.push(SanType::URI(uri.try_into().expect("uri")));
        if with_key_usage {
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        }
        p.custom_extensions.push(ext);
        p.self_signed(&key).expect("self signed").der().to_vec()
    }

    /// A present-but-unparseable basicConstraints (a bare NULL where a SEQUENCE
    /// belongs). rcgen cannot emit this, so it is hand-built.
    fn malformed_basic_constraints(critical: bool) -> CustomExtension {
        let mut bc = CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x05, 0x00]);
        bc.set_criticality(critical);
        bc
    }

    /// A non-critical keyUsage with digitalSignature (BIT STRING 03 02 07 80). The
    /// standard requires keyUsage be critical, so this must be rejected.
    fn noncritical_key_usage() -> CustomExtension {
        let mut ku = CustomExtension::from_oid_content(&[2, 5, 29, 15], vec![0x03, 0x02, 0x07, 0x80]);
        ku.set_criticality(false);
        ku
    }

    /// Test-only bool wrapper over [`authorize_peer`] for the leaf-validation cases.
    fn svid_id_allowed(leaf_der: &[u8], allowed: &[Arc<str>]) -> bool {
        matches!(authorize_peer(leaf_der, allowed), PeerAuth::Allowed)
    }

    // ---- Accepted leaves -------------------------------------------------------

    #[test]
    fn a_conforming_svid_is_accepted() {
        assert!(svid_id_allowed(&conforming(EXPECTED), &[Arc::from(EXPECTED)]));
    }

    #[test]
    fn an_empty_allowlist_accepts_a_conforming_svid() {
        assert!(
            svid_id_allowed(&conforming(EXPECTED), &[]),
            "empty allowlist accepts any valid leaf"
        );
    }

    #[test]
    fn a_multi_segment_path_is_accepted() {
        let id = "spiffe://grid.internal/site/pool-a/node-1";
        assert!(svid_id_allowed(&conforming(id), &[Arc::from(id)]));
    }

    #[test]
    fn an_absent_eku_is_accepted() {
        // EKU is SHOULD, not MUST: a leaf with a conforming keyUsage but no EKU is valid.
        let der = leaf(&[EXPECTED], &[KeyUsagePurpose::DigitalSignature], &[], false);
        assert!(svid_id_allowed(&der, &[]));
    }

    // ---- Rejected leaves: basicConstraints / keyUsage / EKU --------------------

    #[test]
    fn a_ca_flagged_leaf_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            true,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_key_cert_sign_leaf_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign],
            &[],
            false,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_crl_sign_leaf_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::CrlSign],
            &[],
            false,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn an_absent_key_usage_is_rejected() {
        // Section 4.3: keyUsage MUST be present. rcgen omits it when empty.
        let der = leaf(&[EXPECTED], &[], &[], false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_key_usage_without_digital_signature_is_rejected() {
        let der = leaf(&[EXPECTED], &[KeyUsagePurpose::KeyEncipherment], &[], false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_non_critical_key_usage_is_rejected() {
        // Section 4.3: keyUsage MUST be marked critical.
        let der = leaf_with_custom_ext(EXPECTED, noncritical_key_usage(), false);
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn an_eku_with_only_client_auth_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ClientAuth],
            false,
        );
        assert!(
            !svid_id_allowed(&der, &[]),
            "a present EKU must set both server and client auth"
        );
    }

    #[test]
    fn an_eku_with_only_server_auth_is_rejected() {
        let der = leaf(
            &[EXPECTED],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ServerAuth],
            false,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_malformed_basic_constraints_is_rejected_critical_or_not() {
        // A known extension that failed to parse must not read as absent-permissive.
        assert!(!svid_id_allowed(
            &leaf_with_custom_ext(EXPECTED, malformed_basic_constraints(true), true),
            &[]
        ));
        assert!(!svid_id_allowed(
            &leaf_with_custom_ext(EXPECTED, malformed_basic_constraints(false), true),
            &[]
        ));
    }

    // ---- Rejected leaves: SAN / SPIFFE ID --------------------------------------

    #[test]
    fn a_non_spiffe_uri_is_rejected() {
        let der = conforming("https://grid.internal/signals");
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_leaf_without_a_uri_san_is_rejected() {
        let der = leaf(
            &[],
            &[KeyUsagePurpose::DigitalSignature],
            &[ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            false,
        );
        assert!(!svid_id_allowed(&der, &[]));
    }

    #[test]
    fn a_two_uri_san_leaf_names_nobody() {
        let der = leaf(
            &["spiffe://grid.internal/site/a", "spiffe://grid.internal/site/b"],
            &[KeyUsagePurpose::DigitalSignature],
            &[],
            false,
        );
        assert!(
            !svid_id_allowed(&der, &[]),
            "a multi-SAN leaf names nobody and is not a valid SVID"
        );
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

    // ---- Allowlist + authorize_peer diagnostics --------------------------------

    #[test]
    fn allowed_accepts_a_listed_id() {
        let allow: [Arc<str>; 2] = [Arc::from("spiffe://grid.internal/other"), Arc::from(EXPECTED)];
        assert!(svid_id_allowed(&conforming(EXPECTED), &allow));
    }

    #[test]
    fn allowed_rejects_an_unlisted_id() {
        let allow: [Arc<str>; 1] = [Arc::from("spiffe://grid.internal/other")];
        assert!(
            !svid_id_allowed(&conforming(EXPECTED), &allow),
            "an id not in the allowlist is rejected"
        );
    }

    #[test]
    fn allowed_rejects_an_invalid_leaf_even_when_listed() {
        // A CA-flagged leaf is not a valid SVID, so membership cannot rescue it.
        let der = leaf(&[EXPECTED], &[KeyUsagePurpose::DigitalSignature], &[], true);
        let allow: [Arc<str>; 1] = [Arc::from(EXPECTED)];
        assert!(!svid_id_allowed(&der, &allow));
    }

    #[test]
    fn authorize_peer_reports_invalid_leaf() {
        // A non-SVID leaf is InvalidLeaf, distinct from an allowlist miss.
        let der = leaf(&[EXPECTED], &[], &[], false); // no keyUsage
        assert!(matches!(authorize_peer(&der, &[]), PeerAuth::InvalidLeaf));
    }

    #[test]
    fn authorize_peer_reports_not_allowed_with_the_id() {
        let allow: [Arc<str>; 1] = [Arc::from("spiffe://grid.internal/other")];
        let auth = authorize_peer(&conforming(EXPECTED), &allow);
        assert!(
            matches!(&auth, PeerAuth::NotAllowed(id) if id == EXPECTED),
            "expected NotAllowed({EXPECTED}), got {auth:?}"
        );
    }

    #[test]
    fn authorize_peer_reports_allowed_for_a_listed_conforming_svid() {
        assert!(matches!(
            authorize_peer(&conforming(EXPECTED), &[Arc::from(EXPECTED)]),
            PeerAuth::Allowed
        ));
    }

    #[test]
    fn a_garbage_der_is_invalid_leaf() {
        assert!(matches!(
            authorize_peer(b"not a certificate", &[]),
            PeerAuth::InvalidLeaf
        ));
    }
}
